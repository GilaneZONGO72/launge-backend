const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

app.get('/', (req, res) => {
  res.json({ message: '🍽️ Launge Backend fonctionne !' });
});

app.post('/api/restaurants/inscription', async (req, res) => {
  const { nom, ville, telephone, email, mot_de_passe } = req.body;
  const code_unique = 'LNG-' + Math.random().toString(36).substr(2, 6).toUpperCase();
  const hash = await bcrypt.hash(mot_de_passe, 10);
  const { data, error } = await supabase.from('restaurants').insert([
    { nom, ville, telephone, email, mot_de_passe: hash, code_unique }
  ]).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'Restaurant créé !', code_unique, restaurant: data[0] });
});

app.post('/api/restaurants/connexion', async (req, res) => {
  const { email, mot_de_passe } = req.body;
  const { data, error } = await supabase.from('restaurants').select('*').eq('email', email).single();
  if (error || !data) return res.status(400).json({ error: 'Email introuvable' });
  const valide = await bcrypt.compare(mot_de_passe, data.mot_de_passe);
  if (!valide) return res.status(400).json({ error: 'Mot de passe incorrect' });
  if (data.statut === 'en_attente') return res.status(403).json({ error: 'Votre compte est en attente de validation par l\'administrateur.' });
  if (data.statut === 'refuse') return res.status(403).json({ error: 'Votre inscription a été refusée.' });
  const token = jwt.sign({ id: data.id, nom: data.nom }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, restaurant: data });
});

app.get('/api/restaurants', async (req, res) => {
  const { data, error } = await supabase.from('restaurants').select('id, nom, ville').eq('statut', 'valide').order('nom');
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.get('/api/restaurants/code/:code_unique', async (req, res) => {
  const { data, error } = await supabase.from('restaurants').select('id, nom, code_unique, recrutement').eq('code_unique', req.params.code_unique).single();
  if (error || !data) return res.status(404).json({ error: 'Restaurant introuvable' });
  res.json(data);
});
// ── RESTAURANT PAR ID (pour infos recrutement via liste) ──
app.get('/api/restaurants/:id/info', async (req, res) => {
  const { data, error } = await supabase.from('restaurants').select('id, nom, ville, recrutement').eq('id', req.params.id).single();
  if (error || !data) return res.status(404).json({ error: 'Restaurant introuvable' });
  res.json(data);
});
// ── RECRUTEMENT ──
app.put('/api/restaurants/:id/recrutement', async (req, res) => {
  const { recrutement } = req.body;
  const { data, error } = await supabase.from('restaurants').update({ recrutement }).eq('id', req.params.id).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
});

app.post('/api/admin/connexion', async (req, res) => {
  const { email, mot_de_passe } = req.body;
  const { data, error } = await supabase.from('admins').select('*').eq('email', email).single();
  if (error || !data) return res.status(400).json({ error: 'Email introuvable' });
  const valide = await bcrypt.compare(mot_de_passe, data.mot_de_passe);
  if (!valide) return res.status(400).json({ error: 'Mot de passe incorrect' });
  const token = jwt.sign({ id: data.id, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

app.get('/api/admin/restaurants', async (req, res) => {
  const { data, error } = await supabase.from('restaurants').select('id, nom, ville, telephone, email, statut, created_at').order('created_at', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.put('/api/admin/restaurants/:id/valider', async (req, res) => {
  const { data, error } = await supabase.from('restaurants').update({ statut: 'valide' }).eq('id', req.params.id).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
});

app.put('/api/admin/restaurants/:id/refuser', async (req, res) => {
  const { data, error } = await supabase.from('restaurants').update({ statut: 'refuse' }).eq('id', req.params.id).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
});

// ── SUPPRIMER UN RESTAURANT ──
app.delete('/api/admin/restaurants/:id', async (req, res) => {
  const id = req.params.id;
  // Supprimer d'abord les menus liés
  await supabase.from('menus').delete().eq('restaurant_id', id);
  // Supprimer ensuite les commandes liées
  await supabase.from('commandes').delete().eq('restaurant_id', id);
  // Puis supprimer le restaurant
  const { error } = await supabase.from('restaurants').delete().eq('id', id);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'Restaurant supprimé' });
});

app.get('/api/menu/:restaurant_id', async (req, res) => {
  const { data, error } = await supabase.from('menus').select('*').eq('restaurant_id', req.params.restaurant_id);
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.post('/api/menu', async (req, res) => {
  const { restaurant_id, nom, prix, categorie, emoji, stock, seuil_alerte } = req.body;
  const { data, error } = await supabase.from('menus').insert([
    { restaurant_id, nom, prix, categorie, emoji, stock, seuil_alerte }
  ]).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
});

app.put('/api/menu/:id', async (req, res) => {
  const { nom, prix, categorie, emoji, stock, seuil_alerte } = req.body;
  const { data, error } = await supabase.from('menus').update({ nom, prix: +prix, categorie, emoji, stock: +stock, seuil_alerte: +seuil_alerte }).eq('id', req.params.id).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
});

app.delete('/api/menu/:id', async (req, res) => {
  const { error } = await supabase.from('menus').delete().eq('id', req.params.id);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'Plat supprimé' });
});

app.post('/api/commandes', async (req, res) => {
  const { restaurant_id, numero_table, items, total, mode_paiement } = req.body;
  const { data, error } = await supabase.from('commandes').insert([
    { restaurant_id, numero_table, items, total, mode_paiement, statut: 'en_cours' }
  ]).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
});

app.get('/api/commandes/:restaurant_id', async (req, res) => {
  const { data, error } = await supabase.from('commandes').select('*').eq('restaurant_id', req.params.restaurant_id).order('created_at', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.get('/api/stats/:restaurant_id', async (req, res) => {
  const depuis = new Date();
  depuis.setDate(depuis.getDate() - 30);
  const { data, error } = await supabase.from('commandes').select('*').eq('restaurant_id', req.params.restaurant_id).gte('created_at', depuis.toISOString()).order('created_at', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.put('/api/stock/:menu_id', async (req, res) => {
  const { stock } = req.body;
  const { data, error } = await supabase.from('menus').update({ stock }).eq('id', req.params.menu_id).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Launge Backend sur http://localhost:${PORT}`));